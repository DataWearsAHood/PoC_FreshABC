#!/usr/local/bin/python
from __future__ import print_function
from unversioned import ABC_creds, SmoochCreds, SmoochAPI
from datetime import datetime
from time import mktime
from flask import Flask, request#, url_for, send_from_directory
from Crypto.Cipher import AES
from Crypto.Util import Counter
import requests, json, base64, jwt, binascii#, pyaes

print("Starting!")
#print(locals())
#app = Flask(__name__, static_url_path='')
app = Flask(__name__)

BaseApiHdr = {
    "content-type": "application/json",
    "authorization": "Bearer %s" % SmoochCreds['appJWT']
}

# https://developer.apple.com/documentation/businesschat/integrating_with_business_chat#2954303
ABC_JWT_spec = {
    "alg": "HS256",
    "claims": {
        "iss": ABC_creds['cspId'],
        "iat": int(mktime(datetime.now().timetuple()))
    }
}
#print("JWT Params:", ABC_JWT_spec)
# for Py3 (!?) - key must be in AbstractJWKBase (or subclass??)
#jwt = JWT()
#ABC_JWT = jwt.encode(ABC_JWT_spec['claims'], ABC_creds['apiSecret_b64'], ABC_JWT_spec['alg'])
# for Py2
ABC_JWT = jwt.encode(ABC_JWT_spec['claims'], base64.b64decode(ABC_creds['apiSecret_b64']), ABC_JWT_spec['alg'])
#print("ABC_JWT:", ABC_JWT)

with open("listpicker_body.json") as f:
    listpicker_payload = json.load(f)
#print (len(json.dumps(listpicker_payload)))

def sendMessage(appUserId=None, fullPayload=None):
    if appUserId is None:
        # defaults to web appUserId
        appUserId = SmoochCreds['WebAppUserId']

    if fullPayload is None:
        postMessagePayload = {
            "role": "appMaker",
            #"text": "Message us on iMessage: %s" % ABC_creds['Start_URL'],
            "text": "Welcome to iMessage!\nHere is a link that embeds biz-group-id and biz-intent-id:\n"+\
                "https://bcrw.apple.com/urn:biz:{businessId}?biz-intent-id=AdamsBizIntent&biz-group-id=AdamsBizGroup"\
                    .format(businessId=ABC_creds['businessId']),
            "type": "text"
        }
    else: 
        postMessagePayload = fullPayload

    msgPostUrl = SmoochAPI['postMessage'].format(appId=SmoochCreds['appId'], appUserId=appUserId)
    #print(BaseApiHdr, '\n', msgPostUrl)
    if len(json.dumps(postMessagePayload)) > 90000: # limit is 100kb
        msgPostUrl += "/large"
    '''    print("<Long payload (%s) truncated>" % len(json.dumps(postMessagePayload)))
    else:
        print(postMessagePayload)'''

    sendResp = requests.post(msgPostUrl, headers=BaseApiHdr, json=postMessagePayload)
    if sendResp.status_code not in [201, 202]:
        print (sendResp, '\n', sendResp.content)
    else:
        print (' > Sent "%s" (%s: %s)' % (postMessagePayload['text'], sendResp.status_code, msgPostUrl))

    return sendResp

def respond(userText):
    userText = userText.lower()

    if userText in ['list']:
        # Send Listpicker
        sendMessage(SmoochCreds['appUserId'], listpicker_payload)
    else:
        # Send default message
        sendMessage(SmoochCreds['appUserId'])

def getRefPayload(interactiveDataRef):
    # https://developer.apple.com/documentation/businesschat/enhancing_the_customer_s_user_experience/receiving_large_interactive_data_payloads
    # 1 - https://developer.apple.com/documentation/businesschat/handling_message_attachments/getting_the_attachment_s_url
    # 2 - get @ downloadUrl
    # 3 - decrypt payload https://developer.apple.com/documentation/businesschat/handling_message_attachments/downloading_and_decrypting_the_attachment
    # 4 - decode payload: https://developer.apple.com/documentation/businesschat/enhancing_the_customer_s_user_experience/decoding_interactive_data_payloads
    preDownloadHdr = {
        "authorization": "Bearer %s" % ABC_JWT,
        "source-id": ABC_creds['businessId'],
        "url": interactiveDataRef['url'],
        "signature": interactiveDataRef['signature-base64'],
        "owner": interactiveDataRef['owner']
    }
    print (" > GET /preDownload: %s" % "https://mspgw.push.apple.com/v1/preDownload")
    print (preDownloadHdr)
    # 1 - GET /preDownload -> downloadUrl
    preDlResp = requests.get("https://mspgw.push.apple.com/v1/preDownload", headers=preDownloadHdr) # no body
    if preDlResp.status_code not in [200]:
        print (preDlResp, '\n', preDlResp.content)
        return "FAIL!: can't GET /preDownload"
    else:
        assetUrl = json.loads(preDlResp.content)['download-url']
        print (' > got url: "%s"' % assetUrl)

    # 2 - GET downloadUrl -> encrypted payload
    getResp = requests.get(assetUrl)
    if getResp.status_code not in [200]:
        print (getResp, '\n', assetUrl, '\n\t', getResp.content)
        return "FAIL!: can't GET the Encrypted Payload"
    else:
        encryptedPayload = getResp.content
        print (' > got encrypted data (%s bytes)' % len(encryptedPayload))
        #print(type(encryptedPayload), encryptedPayload[:100])

    # 3 - Decrypt payload
    print (' > decrypting data...', end=" ")
    decryptionKey = interactiveDataRef['key'][2:].decode('hex')
    decryptionIV = "0000000000000000" #all-zero, 16-byte initialization vector (IV)

    # https://github.com/ricmoo/pyaes
    '''#print(len(decryptionKey), '\n', decryptionKey)
    aes = pyaes.AESModeOfOperationCTR(decryptionKey)
    decryptedPayload = aes.decrypt(encryptedPayload)'''
    
    # https://stackoverflow.com/questions/3154998/pycrypto-problem-using-aesctr
    #iv = ciphertext[:16]
    ctr = Counter.new(128, initial_value=int(binascii.hexlify(decryptionIV), 16))
    aes = AES.new(decryptionKey, AES.MODE_CTR, counter=ctr)
    decryptedPayload = aes.decrypt(encryptedPayload)
    print ("Done!")
    print(decryptedPayload[:100])

    # 4 - Decode Payload
    decodeHdr={
        "authorization": "Bearer %s" % ABC_JWT,
        "source-id": ABC_creds['businessId'],
        "bid": "42"
    }
    decodeResp = requests.post("https://mspgw.push.apple.com/v1/decodePayload", headers=decodeHdr, data=decryptedPayload)
    if decodeResp.status_code not in [200]:
        print (decodeResp, '\n', assetUrl, '\n\t', decodeResp.content)
        return "FAIL!: can't GET the Decoded Payload"
    else:
        decodedPayload = decodeResp.content
        print (' > got decoded data (%s bytes)' % len(decodedPayload))
        print(type(decodedPayload), decodedPayload[:100])

    return "WIP!"

@app.route('/webhooks', methods=['POST'])
def handle_webhook():
    # VVV Insert your own Bot reply logic here! VVV
    data=json.loads(request.data)
    #print("Received webhook with %s messages" % len(data['messages']))
    #userId = data['messages'][0]['authorId']
    trigger = data['trigger']

    print (" > Received %s webhook:" % (trigger))
    if trigger.startswith("message:"):
        userText = data['messages'][0]['text'].lower()
        print ("\t%s" % data)
        if trigger in ['message:appUser']:
            respond(userText)
            return "OK!"
        elif trigger in ['message:appMaker']:
            pass
            return "OK!"

    elif trigger.startswith("passthrough:apple:"):
        print ("\t%s" % data)
        if trigger in ['passthrough:apple:interactive']:
            payload_apple = data['payload']['apple']
            if 'interactiveDataRef' in payload_apple.keys():
                getRefPayload(payload_apple['interactiveDataRef'])
                return "OK!"
            elif 'interactiveData' in payload_apple.keys():
                pass

    print (data)
    return " > Unrecognized trigger!"

@app.route('/', methods=['HEAD'])
def head_request():
    return "OK!"

if __name__ == "__main__":
    #print ("Server running in folder %s" % os.getcwd())
    app.run()
