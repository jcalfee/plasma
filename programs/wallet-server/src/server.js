import express from "express";
import limit from "express-better-ratelimit";
import {createStore, applyMiddleware} from "redux";
import reducer from "./reducer";
import createMiddleware from "./middleware";
import * as actions from "./actions";
import * as restApi from "./rest-api";
// import {checkToken} from "@graphene/time-token";

const {
    /** Server listen port */
    npm_package_config_rest_port,

    /** Limit the number of wallet requests it accepts per IP address to a fixed number per hour. */
    npm_package_config_rest_ip_requests_per_hour,

} = process.env;

const ratelimitConfig = {
    duration: 60 * 60 * 1000, // 1 hour
    max: npm_package_config_rest_ip_requests_per_hour
};

export default function createServer() {
    const createStoreWithMiddleware = applyMiddleware(createMiddleware())(createStore);
    const store = createStoreWithMiddleware(reducer);

    const app = express();

    app.use((req, res, next) => {
        const origin = req.get("Origin");
        res.set("Access-Control-Allow-Origin", origin);
        res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        res.set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type");
        res.set("Access-Control-Allow-Credentials", "true");
        next();
    });

    // Limit number of requests per hour by IP
    console.log("Limit by IP address", {
        max: ratelimitConfig.max,
        duration: ratelimitConfig.duration / 1000 / 60 + " min"
    });
    app.use(limit(ratelimitConfig));
    app.get("/:methodName", restApi.get(actions, store.dispatch));
    app.post("/:methodName", restApi.post(actions, store.dispatch));
    const server = app.listen(npm_package_config_rest_port);
    server.on("listening", () => { console.log("Server listening port %d", npm_package_config_rest_port); });
    server.on("close", () => { console.log("Server closed port %d", npm_package_config_rest_port); });
    server.on("error", error => {
        console.error("wallet-server::createServer\t", error, error.stack);
        console.error("wallet-server::createServer\trestart");
        createServer();
    });
    return { server, app };
}
