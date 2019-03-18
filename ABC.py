#!/usr/local/bin/python
from __future__ import print_function
from unversioned import ABC_creds, SmoochCreds, SmoochAPI
from datetime import datetime
from time import mktime
from flask import Flask, request#, url_for, send_from_directory
#from Crypto.Cipher import AES
#from Crypto.Util import Counter
import requests, json, base64, jwt#, binascii, pyaes

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
        "iat": int(mktime(datetime.now().timetuple()))#,
        #"exp": int(mktime(datetime.now().timetuple())) + (24 * 60 * 60)
    }
}
#print("JWT Params:", ABC_JWT_spec)
# for Py3 (!?) - key must be in AbstractJWKBase (or subclass??)
#jwt = JWT()
#ABC_JWT = jwt.encode(ABC_JWT_spec['claims'], ABC_creds['apiSecret_b64'], ABC_JWT_spec['alg'])
# for Py2
ABC_JWT = jwt.encode(ABC_JWT_spec['claims'], base64.b64decode(ABC_creds['apiSecret_b64']), ABC_JWT_spec['alg'])
print("ABC_JWT:", ABC_JWT)

appleApiBaseUrl = ""
lambdaBaseUrl = "https://paxfg5t5h0.execute-api.us-east-1.amazonaws.com/dev"

with open("listpicker_body.json") as f:
    listpicker_payload = json.load(f)
#print (len(json.dumps(listpicker_payload)))

def sendMessage(appUserId=None, fullPayload=None, responseType=None):
    if appUserId is None:
        # defaults to web appUserId
        appUserId = SmoochCreds['WebAppUserId']

    if fullPayload is None:
        postMessagePayload = {
            "role": "appMaker",
            "type": "text"
        }
        if responseType in ['group']:
            postMessagePayload['text'] = "Welcome to iMessage!\nHere is a link that embeds biz-group-id and biz-intent-id:\n"+\
                    "https://bcrw.apple.com/urn:biz:{businessId}?biz-intent-id=AdamsBizIntent&biz-group-id=AdamsBizGroup"\
                        .format(businessId=ABC_creds['businessId'])
        elif responseType in ['link']:
            postMessagePayload['text'] = "Message us on iMessage: %s" % ABC_creds['Start_URL']
        elif responseType in ['location']:
            postMessagePayload['text'] = "Where are you now?"
        elif responseType in ['pay']:
            postMessagePayload['text'] = "Thanks for your payment"
        elif responseType in ['list']:
            postMessagePayload = listpicker_payload
        else:
        #if ResponseType in [None, 'welcome']:
            postMessagePayload['text'] = "Welcome to iMessage!"
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

    sent=0
    for option in ['location', 'pay', 'list', 'group', 'link']:
        if option in userText:
            sendMessage(SmoochCreds['appUserId'], responseType=option)
            sent+=1
    if sent == 0:           
        # Send default message
        sendMessage(SmoochCreds['appUserId'])

def getRefPayload(interactiveDataRef, apple_payload_id):
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

    if True:
        dlDecodeData = {
            "downloadUrl": assetUrl,
            "intDataRefKey": interactiveDataRef['key']
        }
        dlDecodeResp = requests.post(lambdaBaseUrl+'/dlDecrypt', json=dlDecodeData)
        print (' > got decode response: "%s"' % dlDecodeResp.status_code)
        if dlDecodeResp.status_code not in [200]:
            print (dlDecodeResp, '\n\t', dlDecodeResp.content)
            return "FAIL!: can't GET the Encrypted Payload"
        else:
            decryptedPayload = base64.b64decode(dlDecodeResp.content)
            #decryptedPayload = dlDecodeResp.content
            print (' > got decoded payload: \n\t"%s"' % decryptedPayload[:200])

    else:   # previous attempts to decrypt
        # 2 - GET downloadUrl -> encrypted payload
        getResp = requests.get(assetUrl)
        if getResp.status_code not in [200]:
            print (getResp, '\n', assetUrl, '\n\t', getResp.content)
            return "FAIL!: can't GET the Encrypted Payload"
        else:
            encryptedPayload = getResp.content
            #encryptedB64Payload = getResp.content
            print (' > got encrypted data (%s bytes)' % len(encryptedPayload))
            #print (' > got encrypted data (%s bytes)' % len(encryptedB64Payload))
            #print(type(encryptedB64Payload), encryptedB64Payload[:100])

        # 3 - Decrypt payload
        #print (' > decrypting data...', end=" ")
        print (' > decrypting data...')
        '''decryptionKey = interactiveDataRef['key'][2:].decode('hex')
        #decryptionIV = "0000000000000000" #all-zero, 16-byte initialization vector (IV)
        decryptionIV = b"0" * 16
        encryptedPayload = base64.b64decode(encryptedB64Payload)    # base64 encoded or not??
        #encryptedPayload = encryptedB64Payload
        '''
        # https://github.com/ricmoo/pyaes
        #print(len(decryptionKey), '\n', decryptionKey)
        '''aes = pyaes.AESModeOfOperationCTR(decryptionKey)
        decryptedPayload = aes.decrypt(encryptedPayload)
        #decryptedPayload = aes.decrypt(decryptionIV+encryptedPayload)
        '''
        # https://stackoverflow.com/questions/3154998/pycrypto-problem-using-aesctr
        '''
        #iv = ciphertext[:16]
        ctr = Counter.new(128, initial_value=int(binascii.hexlify(decryptionIV), 16))
        aes = AES.new(decryptionKey, AES.MODE_CTR, counter=ctr)
        #decryptedPayload = aes.decrypt(encryptedPayload)
        decryptedPayload = aes.decrypt(decryptionIV+encryptedPayload)
        '''
        # https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
        '''iv_int = int(iv.encode('hex'), 16) 
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

        # Create AES-CTR cipher.
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        # Decrypt and return the plaintext.
        plaintext = aes.decrypt(ciphertext)'''

        decryptHdr = { "intDataRefKey": interactiveDataRef['key']}
        #print(requests.post(lambdaBaseUrl+'/echo', data=encryptedPayload, headers=decryptHdr).content[:1000])
        decryptResp = requests.post(lambdaBaseUrl+'/decryptOnly', data=base64.b64encode(encryptedPayload), headers=decryptHdr)
        print (decryptResp, '\n\t', decryptResp.content)
        if decryptResp.status_code not in [200]:
            return "Fail!"
        else:
            decryptedPayload = decryptResp.content 
            print ("Done!")
            print(decryptedPayload[:100])

    # 4 - Decode Payload
    decodeHdr={
        "authorization": "Bearer %s" % ABC_JWT,
        "source-id": ABC_creds['businessId'],
        "bid": interactiveDataRef['bid']
    }
    #print (" > trying to /decodePayload...")
    decodeResp = requests.post("https://mspgw.push.apple.com/v1/decodePayload", headers=decodeHdr, data=decryptedPayload)
    if decodeResp.status_code not in [200]:
        print (decodeResp, '\n', assetUrl, '\n\t', decodeResp.content)
        print ("FAIL!: can't GET the Decoded Payload")
        return "Fail!"
 
    decodedPayload = decodeResp.content
    print (' > got decoded data (%s bytes)' % len(decodedPayload))
    print(type(decodedPayload), decodedPayload[:1000])

    return "OK!"

@app.route('/webhooks', methods=['POST'])
def handle_webhook():
    # VVV Insert your own Bot reply logic here! VVV
    global data
    data=json.loads(request.data)
    #print("Received webhook with %s messages" % len(data['messages']))
    #userId = data['messages'][0]['authorId']
    trigger = data['trigger']

    print (" > Received %s webhook:" % (trigger))
    if trigger.startswith("message:"):
        userText = data['messages'][0]['text'].lower()
        if trigger in ['message:appUser']:
            print ("\t%s" % data)
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
                getRefPayload(payload_apple['interactiveDataRef'], payload_apple['id'])
                #respond("list")
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
