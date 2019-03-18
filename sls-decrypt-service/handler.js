'use strict';

const crypto = require('crypto'); 
const request = require("request-promise-native");
const { PassThrough } = require("stream");
const concat = require('concat-stream');

/*
module.exports.hello = async (event, context) => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Go Serverless v1.0! Your function executed successfully!',
      input: event,
    }),
  };

  // Use this code if you don't use the http event with the LAMBDA-PROXY integration
  // return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
};

module.exports.echo = async (event, context) => {
  console.log("Launching echo")
  console.log(event['headers']['intDataRefKey'])
  console.log(event['body'].substr(0,100))
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'Go Serverless v1.0! Your function executed successfully!',
      input: event,
    }),
  };

  // Use this code if you don't use the http event with the LAMBDA-PROXY integration
  // return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
};
*/

module.exports.dlDecrypt = async (event, context) => {
  // from MikeS
  console.log("Launching dlDecrypt");
  const body = JSON.parse(event['body']);
  console.log(body.downloadUrl, body.intDataRefKey)

  //const fileStream = await endpoint.getFileStream(body.downloadUrl);
  const fileStream = await Apple._downloadFile(body.downloadUrl);
  console.log("creating cipher")
  const initializationVector = Buffer.alloc(16);
  const decryptionKey = body.intDataRefKey.substr(2);
  const cipher = crypto.createDecipheriv(
      'aes-256-ctr',
      Buffer.from(decryptionKey, 'hex'),
      initializationVector,
  );
  console.log("decrypting stream")
  const encodedPayload = await new Promise((resolve, reject) => {
      fileStream.pipe(cipher).pipe(
          concat((data) => {
              resolve(data);
          }),
      );
  });
  console.log("returning stream")
  console.log(encodedPayload)
  return {
    statusCode: 200,
    body: encodedPayload.toString('base64'),
  };

  // Use this code if you don't use the http event with the LAMBDA-PROXY integration
  // return { message: 'Go Serverless v1.0! Your function executed successfully!', event };
};

class Apple {
  /**
   * Get an Apple endpoint url
   * @param {string} endpoint Apple API endpoint
   * @returns {string} Apple endpoint URL
   */
  static _url(endpoint) {
    return `https://mspgw.push.apple.com/v1${endpoint}`;
  }

  /**
   * Generates a token to be included in authenticated requests
   * @param {string} apiSecret API secret to use to sign token
   * @param {string} cspId ID of the CSP signing the token
   * @returns {string} an authentication token
   * /
  static _generateToken({ apiSecret, cspId }) {
    const secret = Buffer.from(apiSecret, "base64");
    return jwt.sign({}, secret, { issuer: cspId });
  }
  */

  /**
   * Downloads a file at the given URL. Helper method to simplify `decodeLargePayload`
   *
   * @param {string} downloadUrl URL of the file to download
   * @returns {object} input stream of the downloaded file
   */
  static _downloadFile(downloadUrl) {
    console.log("starting downloadFile:", downloadUrl);
    return new Promise((resolve, reject) => {
      const req = request.get(downloadUrl);

      req.on("response", res => {
        if (res.statusCode > 399) {
          reject(new Error(`Unexpected status code ${res.statusCode}`));
        } else {
          const passthrough = new PassThrough();
          res.pipe(passthrough);
          resolve(passthrough);
        }
      });

      req.on("error", err => {
        //logger.debug("Error while trying to download file", err);
        console.log("Error while trying to download file", err);
        reject(err);
      });
    });
  }

  /**
   * Downloads a file at the given URL. Helper method to simplify `decodeLargePayload`
   *
   * @param {object} inputStream URL of the file to download
   * @param {object} headers Request headers
   * @returns {object} input stream of the decoded payload stream
   * /
  static _decodeStream(inputStream, headers) {
    console.log("starting decodeStream");
    return new Promise((resolve, reject) => {
      const req = request.post({
        url: Apple._url("/decodePayload"),
        headers,
        body: inputStream
      });

      req.on("response", res => {
        if (res.statusCode > 399) {
          reject(new Error(`Unexpected status code ${res.statusCode}`));
        } else {
          const passthrough = new PassThrough();
          res.pipe(passthrough);
          resolve(passthrough);
        }
      });

      req.on("error", err => {
        //logger.debug("Error while trying to decode stream", err);
        console.log("Error while trying to decode stream", err);
        reject(err);
      });
    });
  }

  /**
   * Parses a stream into an object
   *
   * @param {object} stream the stream to be parsed
   * @returns {object} parsed stream
   * /
  static _parseStream(stream) {
    console.log("starting decodeStream");
    return new Promise((resolve, reject) => {
      let string = "";
      stream.on("data", data => {
        string += data.toString();
      });
      stream.on("end", () => {
        try {
          const payload = JSON.parse(string);
          resolve(payload.data);
        } catch (error) {
          reject(error);
        }
      });
    });
  }

  /**
   * Decodes a large interactive payload from Apple
   *
   * @param {object} interactiveDataRef large interactive payload from Apple
   * @param {string} businessId Apple Business Chat ID
   * @param {object} config Apple config
   * @param {string} config.apiSecret API secret to use to sign token
   * @param {string} cspId ID of the CSP signing the token
   * @returns {object} the decoded payload
   * /
  //static async decodeLargePayload(interactiveDataRef, businessId, config) {
  static async decodeLargePayload(interactiveDataRef, businessId) {
    console.log("starting decodeLargePayload");
    //console.log(token);
      const headers = {
      "source-id": businessId,
      //authorization: `Bearer ${this._generateToken(config)}`,
      authorization: `Bearer ${token}`,
      url: interactiveDataRef.url,
      signature: interactiveDataRef["signature-base64"],
      owner: interactiveDataRef.owner,
      bid: interactiveDataRef.bid
    };
    console.log(headers);

    const { "download-url": downloadUrl } = await request.get({
      url: Apple._url("/preDownload"),
      json: true,
      headers
    });

    const inputStream = await Apple._downloadFile(downloadUrl);

    const cipher = Crypto.createDecipheriv(interactiveDataRef.key.substr(2));

    const decodedStream = await Apple._decodeStream(inputStream.pipe(cipher), headers);

    return Apple._parseStream(decodedStream);
  }
  */
}
