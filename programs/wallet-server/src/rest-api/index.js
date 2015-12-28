import http from "http";
import Busboy from "busboy";

const uploadLimit = {
    fields: process.env.npm_config__graphene_rest_api_fields || 100,
    fieldSize: process.env.npm_config__graphene_rest_api_fieldSize || 20 * 1024,
    files: process.env.npm_config__graphene_rest_api_files || 10,
    fileSize: process.env.npm_config__graphene_rest_api_fileSize || 1000 * 1024,
    parts: process.env.npm_config__graphene_rest_api_parts || 110, // fields + files
    headerPairs: process.env.npm_config__graphene_rest_api_headerPairs || 110
};

const debug = process.env.npm_config__graphene_rest_api_debug || false;

// httpResponse helpers..  Create: response_codes = { "Accepted": 202, ...}
const response_codes = {};
for (const code in http.STATUS_CODES) response_codes[http.STATUS_CODES[code].toLowerCase()] = code;

/** Express will crash the entrire server process if any middleware throws an exception */
function uncaught(error) {
    console.error("ERROR\trest-api\t", error, error.stack);
}

/**
 @param {expressjs.Request} res
 @param {string} message - A valid HTTP status message (@see http.STATUS_CODES)
 @param {object} [data={}] - Optional additional data returned in the response (`code` and `message` variables are added)
 */
export function httpResponse(res, message, data = {}) {
    const code = response_codes[message.toLowerCase()];
    if (!code) throw "Unknown HTTP Status message: " + message;
    if (data === null || typeof data !== "object") data = { message: data };
    // Add the HTTP Response code to the JSON body
    data.status = code;
    data.statusText = message;
    // Set the Header HTTP Response code and send a JSON body reply
    res.status(code).json(data);
}

/** Simple HTTP status callbacks used to reply to the client */
function reply(res, action) {
    action.reply = (message, data) => {
        if (message.then) { // Promise
            message
                .then(data1 => {
                    if (typeof data1 === "string") {
                        // Try to convert a valid reponse strings into a code: like "Not Modified"
                        const code = response_codes[data1.toLowerCase()];
                        if (code !== null) {
                            httpResponse(res, data1);
                            return;
                        }
                    }
                    const code_description = data1.code_description || "OK";
                    httpResponse(res, code_description, data1);
                })
                .catch(error => {
                    console.log("ERROR\trest-api\t", JSON.stringify(error));
                    httpResponse(res, "Bad Request", error);
                });
            return;
        }
        httpResponse(res, message, data);
    };
    action.reply.ok = data => { httpResponse(res, "OK", data); };
    action.reply.badRequest = data => { httpResponse(res, "Bad Request", data); };
}

/** @typedef expressjs.Request - {@link http://expressjs.com/4x/api.html#req}
 */

/**
    Middleware for the Express Js GET requests.  The Express JS URL pattern needs to have
    a methodName variable.

    @param {object} api - methods on this API are involved in response to matching GET requests
    @param {object} dispatch - function that accepts the `sugared` return value from your API"s return value.

    ```javascript
    var myApi = { myMethod: ({ var1 }) => { return { action: "name", ... } } }
    var dispatch = action => { action.reply.ok({ result: 123 }) }
    app.get("/:methodName", restApi.get(myApi, dispatch))
    ```
    ```bash
    curl http://localhost:9080/myMethod?var1=1111
    ```
*/
export const get = (api, dispatch) => (req, res) => {
    try {
        const methodFunction = api[req.params.methodName];
        if (!methodFunction) {
            if (debug) console.error("GET unknown method", req.params.methodName);
            httpResponse(res, "Bad Request", { error: "Unknown method" });
            return;
        }
        try {
            const action = methodFunction(req.query);
            console.log("GET", "action", req.params.methodName, action);
            if (!action || !dispatch) {
                httpResponse(res, "OK");
                return;
            }
            // Allow the reducer to reply with a message
            reply(res, action);
            dispatch(action);
        } catch (error) {
            console.error("GET error", error, error.stack);
            httpResponse(res, "Bad Request", typeof error === "string" ? {error} : undefined);
        }
    } catch (error) { uncaught(error); }
};

/**
    Middleware for the Express Js POST requests.  The request URL should be your API method name.

    ```javascript
    var myApi = { upload: function({ filename, var1, var2 }) { ...  }}
    var dispatch = action => { action.reply.ok({ result: 123 }) }
    app.post("/*", restApi.post(myApi, dispatch))
    ```
    ```bash
    curl -X POST -F "fileupload=@myFile.bin;filename=myFile" -F var1=1111 -F var2=2222 http://localhost:9999/upload
    ```
*/
export const post = (api, dispatch) => (req, res) => {
    try {
        const methodName = req.params.methodName;
        const busboy = new Busboy({ headers: req.headers, limits: uploadLimit });
        const params = {};
        // busboy will parse the mime message format into events
        busboy.on("file", (fieldname, file, filename, encoding, mimetype) => {
            if (mimetype !== "application/octet-stream") {
                // warn but continue
                console.error("Expecting mimetype application/octet-stream", fieldname, file, filename, encoding, mimetype);
            }
            let buffer;
            file.on("data", (data) => { buffer = data; });
            file.on("end", () => { params[filename] = buffer.toString("binary"); });
        });
        busboy.on("field", (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) => {
            if (mimetype !== "text/plain") {
                // warn but continue
                console.error("Expecting mimetype text/plain", fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype);
            }
            params[fieldname] = val;
        });
        busboy.on("finish", () => {
            try {
                const methodFunction = api[methodName];
                if (!methodFunction) {
                    console.error("POST unknown method", methodName);
                    httpResponse(res, "Bad Request", { error: "Unknown method" });
                    return;
                }
                const action = methodFunction(params);
                if (debug) console.error("POST", "action", req.params.methodName, action);
                if (!action || !dispatch) {
                    httpResponse(res, "OK");
                    return;
                }
                // Allow the reducer to reply with a message
                reply(res, action);
                dispatch(action);
            } catch (error) {
                console.error("POST error", error, error.stack);
                httpResponse(res, "Bad Request", typeof error === "string" ? {error} : undefined);
            }
        });
        req.pipe(busboy);
    } catch (error) { uncaught(error); }
};
