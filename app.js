/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
  
/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('./config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));


//Initialize node-mySQL
var mysql = require("mysql");

var db_config = {
  host: config.databaseHost,
  user: config.databaseUser,
  password: config.databasePass,
  database: "ericturn_restaurant"
};

var con;

function handleDisconnect() {
  con = mysql.createConnection(db_config); // Recreate the connection, since
                                                  // the old one cannot be reused.

  con.connect(function(err) {              // The server is either down
    if(err) {                                     // or restarting (takes a while sometimes).
      console.log('error when connecting to db:', err);
      setTimeout(handleDisconnect, 2000); // We introduce a delay before attempting to reconnect,
    }                                     // to avoid a hot loop, and to allow our node script to
  });                                     // process asynchronous requests in the meantime.
                                          // If you're also serving http, display a 503 error.
  con.on('error', function(err) {
    console.log('db error', err);
    if(err.code === 'PROTOCOL_CONNECTION_LOST') { // Connection to the MySQL server is usually
      handleDisconnect();                         // lost due to either server restart, or a
    } else {                                      // connnection idle timeout (the wait_timeout
      throw err;                                  // server variable configures this)
    }
  });
}

handleDisconnect();



//Finding Restaurant Mode
var findRest = 0;

//Restaurant Type
var restType;
var restaurantChoices = [];

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (config.APP_SECRET);/* ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');*/
  
// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (config.VALIDATION_TOKEN); /* ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');*/
  
// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (config.PAGE_ACCESS_TOKEN); /*?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');*/
  
// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (config.SERVER_URL); /* ?
  (process.env.SERVER_URL) :
  config.get('serverURL');*/
console.log("SERVER_URL: " + SERVER_URL);
if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    throw new Error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
	console.log(quickReplyPayload);
	
	//First Quick Reply Set, Yes or No to Finding a Restaurant
    if(quickReplyPayload == "RESTAURANT_YES"){
		console.log("Restaurant Path");
		sendTypingOn(senderID);
		findMealType(senderID);
	}
	else if (quickReplyPayload == "RESTAURANT_NO"){
    console.log("Meal Path");
		sendTypingOn(senderID);
		findFoodType(senderID);
	}
	
	//Second Quick Reply, Path 1, Find Fast Food or Restaurant
	if(quickReplyPayload == "RESTAURANT_FAST"){
		console.log("Retrieving Fast Food Restaurant");
		sendTypingOn(senderID);
		restType = "Fast";
		getRestaurant(senderID, restType);
	}
	else if (quickReplyPayload == "RESTAURANT_DINE"){
		console.log("Retrieving Dine-In Restaurant");
		sendTypingOn(senderID);
		restType = "Dine";
		getRestaurant(senderID, restType);
  }
  //Second Quick Reply, Path 2, Find Fast Food or Restaurant
	if(quickReplyPayload == "MEAL_BREAKFAST"){
		console.log("Retrieving Fast Food Restaurant");
		sendTypingOn(senderID);
		var mealType = "BREAKFAST";
		findFoodDifficulty(senderID, mealType);
	}
	else if (quickReplyPayload == "MEAL_LUNCH"){
		console.log("Retrieving Dine-In Restaurant");
		sendTypingOn(senderID);
		var mealType = "LUNCH";
		findFoodDifficulty(senderID, mealType);
  }
  else if (quickReplyPayload == "MEAL_DINNER"){
		console.log("Retrieving Dine-In Restaurant");
		sendTypingOn(senderID);
		var mealType = "DINNER";
		findFoodDifficulty(senderID, mealType);
  }
  //Third Quick Reply for meals Parse out the difficulty and the type
  if(quickReplyPayload.startsWith("EASY") || quickReplyPayload.startsWith("MEDIUM") || quickReplyPayload.startsWith("ADVANCED")){
    console.log("Retrieving Meal and Difficulty");
    //Payload will be something like EASY_BREAKFAST, this will parse it into a variable
    var meal = quickReplyPayload.split("_");
    sendTypingOn(senderID);
    //Send the parsed difficulty and type and sender ID to grab a meal from DB
    getMeal(senderID,meal[1], meal[0]);
	}
	/*
	else{
		sendTypingOn(senderID);
		sendTextMessage(senderID, "Quick Reply Action Received. ")
	}
	*/
    return;
  }

  if (messageText) {
	var restaurant = messageText.includes("eat" || "restaurant")
	if(restaurant){
		sendTypingOn(senderID);
		sendRestaurant(senderID);
	}
	else{
		sendTypingOn(senderID);
		sendErrorReply(senderID);
	}
  } else if (messageAttachments) {
    if(findRest == 1)
	{
		var lat = messageAttachments[0].payload.coordinates.lat;
		var lng = messageAttachments[0].payload.coordinates.long;
	}
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // If the 'Another Button' is selected it will run this
  if (payload == "RESTAURANT_ANOTHER"){
	  sendTypingOn
	  findMealType(senderID);
  }
  else if (payload == "MEAL_ANOTHER"){
	  sendTypingOn
	  findFoodType(senderID);
  }
  else if (payload == "RESTAURANT_FIND"){
	  sendTypingOn
	  sendTextMessage(recipientID,"Send me your location and I'll find the nearest one!");
	  findRest = 1;
  }
  else{
	  sendTextMessage(recipientID,"Acknowledged.");
  }
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}



/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };
  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendMap(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

//Meal Methods
//Send the meal message
function sendMeal(recipientId, mealName, mealPicture) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: mealName,
            subtitle: "This looks good!",              
            image_url: mealPicture,
            buttons: [
              {
                type: "postback",
                payload: "MEAL_ANOTHER",
                title: "🏡 Another!"
              },
              {
                type: "postback",
                payload: "RESTAURANT_ANOTHER",
                title: "🍽️ Restaurant!"
              }],
          }]
        }
      }
    }
  };  

  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

function getMeal(senderID, mealType, levelofDifficulty){
		con.query('select picture, name from meals WHERE type = "' + mealType + '" AND difficulty = "' + levelofDifficulty+ '"',function(err,rows){
            if(!err) {randomPicker(senderID, rows, 'meal');} 
            else{console.log(err);}          
        });
	
}

/*
 * Send the restaurant message
 *
 */
function sendRestaurant(recipientId,restaurantName, restaurantIndex) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: restaurantName,
            subtitle: "You should eat here!",              
            image_url: SERVER_URL + "/assets/restaurants/"+restaurantIndex+".jpg",
            buttons: [{
              type: "postback",
              payload: "MEAL_ANOTHER",
              title: "🏡 Eat at home!"
            },
            {
              type: "postback",
              payload: "RESTAURANT_ANOTHER",
              title: "🍽️ Another!"
            }],
          }]
        }
      }
    }
  };  

  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

function getRestaurant(senderID, restaurantType){
	if (restaurantType == "Fast"){
		con.query("select picture, name from restaurants WHERE type = 'fast' ",function(err,rows){
            if(!err) {randomPicker(senderID, rows, 'restaurant');}           
        });
	}
	else if (restaurantType == "Dine"){
		con.query("select picture, name from restaurants WHERE type = 'dine' ",function(err,rows){
            if(!err) {randomPicker(senderID, rows, 'restaurant');}           
        });
	}
	
	else{
		console.log("Using getRestaurant fallback method");
		restaurantChoices = [
		"McDonalds", 		//0
		"Burger King", 		//1
		"Steak N Shake", 	//2
		"Hardees", 			//3
		"Wendys", 			//4
		"Starbucks", 		//5
		"Texas Roadhouse", 	//6
		"Denny's",			//7
		"Rally's"			//8
		];
		var position = Math.floor(Math.random() * restaurant.length);
		var choice = restaurant[position];
		var picture = position;
		
		sendRestaurant(senderID, choice, picture);
	}
	
	
}

function randomPicker(senderID, value, type){
	
	restaurantChoices = value;
	console.log(restaurantChoices);
	var restParse = JSON.parse(JSON.stringify(restaurantChoices));
	console.log(restParse);
	var position = Math.floor(Math.random() * restaurantChoices.length);
	var choice = restParse[position].name;
	var picture = restParse[position].picture;
  
  if(type == 'restaurant')
    sendRestaurant(senderID, choice, picture);
  else if(type == 'meal')
    sendMeal(senderID, choice, picture);
}


/*
 * Send a message with Quick Reply buttons.
 *
 */
 //Default catch all quick reply
function sendErrorReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Are you wanting a meal at home or dining out?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"🍽️ Dining Out!",
          "payload":"RESTAURANT_YES"
        },
        {
          "content_type":"text",
          "title":"🏡 At home!",
          "payload":"RESTAURANT_NO"
        }
      ]
    }
  };
  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

function findFoodDifficulty(recipientId, foodType) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "How easy to make are you wanting it to be?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"🍳 Easy!",
          "payload":"EASY_" + foodType
        },
        {
          "content_type":"text",
          "title":"🥪 Medium!",
          "payload":"MEDIUM_" + foodType
        },
        {
          "content_type":"text",
          "title":"🍽 Advanced!",
          "payload":"ADVANCED_" + foodType
        }
      ]
    }
  };
  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

function findFoodType(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What type of meal are you wanting?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"🍳 Breakfast!",
          "payload":"MEAL_BREAKFAST"
        },
        {
          "content_type":"text",
          "title":"🥪 Lunch!",
          "payload":"MEAL_LUNCH"
        },
        {
          "content_type":"text",
          "title":"🍽 Dinner!",
          "payload":"MEAL_DINNER"
        }
      ]
    }
  };
  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

function findMealType(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Do you want fast food or a dine-in restaurant?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"🍟 Fast Food!",
          "payload":"RESTAURANT_FAST"
        },
        {
          "content_type":"text",
          "title":"🍽 Restaurant!",
          "payload":"RESTAURANT_DINE"
        }
      ]
    }
  };
  sendTypingOff(recipientId);
  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

