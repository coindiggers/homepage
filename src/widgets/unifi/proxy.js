import cache from "memory-cache";

import getServiceWidget from "utils/config/service-helpers";
import { getPrivateWidgetOptions } from "utils/config/widget-helpers";
import createLogger from "utils/logger";
import { formatApiCall } from "utils/proxy/api-helpers";
import { addCookieToJar, setCookieHeader } from "utils/proxy/cookie-jar";
import { httpProxy } from "utils/proxy/http";
import widgets from "widgets/widgets";

const udmpPrefix = "/proxy/network";
const proxyName = "unifiProxyHandler";
const prefixCacheKey = `${proxyName}__prefix`;
const logger = createLogger(proxyName);

// Placeholder for session clearing logic
function clearSessionForService(service) {
  logger.debug(`Clearing session for service '${service}'`);
  // This is where you'd clear cookies or reset session storage if needed
  // If you're using a custom cookie jar per service/host, you'd clear it here
}

async function getWidget(req) {
  const { group, service, index } = req.query;

  let widget = null;

  if (group === "unifi_console" && service === "unifi_console") {
    const infowidgetIndex = req.query?.query ? JSON.parse(req.query.query).index : undefined;
    widget = await getPrivateWidgetOptions("unifi_console", infowidgetIndex);
    if (!widget) {
      logger.debug("Error retrieving settings for this Unifi widget");
      return null;
    }
    widget.type = "unifi";
  } else {
    if (!group || !service) {
      logger.debug("Invalid or missing service '%s' or group '%s'", service, group);
      return null;
    }

    widget = await getServiceWidget(group, service, index);
    if (!widget) {
      logger.debug("Invalid or missing widget for service '%s' in group '%s'", service, group);
      return null;
    }
  }

  return widget;
}

async function login(widget, csrfToken) {
  const endpoint = widget.prefix === udmpPrefix ? "auth/login" : "login";
  const api = widgets?.[widget.type]?.api?.replace("{prefix}", ""); // no prefix for login
  const loginUrl = new URL(formatApiCall(api, { endpoint, ...widget }));
  const loginBody = {
    username: widget.username,
    password: widget.password,
    remember: true,
    rememberMe: true,
  };
  const headers = { "Content-Type": "application/json" };

  if (csrfToken) {
    headers["X-CSRF-TOKEN"] = csrfToken;
  }

  const [status, contentType, data, responseHeaders] = await httpProxy(loginUrl, {
    method: "POST",
    body: JSON.stringify(loginBody),
    headers,
  });

  return [status, contentType, data, responseHeaders];
}

export default async function unifiProxyHandler(req, res) {
  const widget = await getWidget(req);
  const { service, endpoint } = req.query;

  if (!widget) {
    return res.status(400).json({ error: "Invalid proxy service type" });
  }

  const api = widgets?.[widget.type]?.api;
  if (!api) {
    return res.status(403).json({ error: "Service does not support API calls" });
  }

  let [status, contentType, data, responseHeaders] = [];
  const headers = {};
  let csrfToken;
  let prefix = cache.get(`${prefixCacheKey}.${service}`);

  // Determine prefix
  if (widget.key) {
    prefix = udmpPrefix;
    headers["X-API-KEY"] = widget.key;
    headers["Accept"] = "application/json";
  } else if (prefix === null) {
    // No cached prefix — detect it
    [status, contentType, data, responseHeaders] = await httpProxy(widget.url);
    let detectedPrefix = "";

    if (responseHeaders?.["x-csrf-token"]) {
      detectedPrefix = udmpPrefix;
      csrfToken = responseHeaders["x-csrf-token"];
    } else if (
      responseHeaders?.["access-control-expose-headers"] ||
      responseHeaders?.["Access-Control-Expose-Headers"]
    ) {
      detectedPrefix = udmpPrefix;
    }

    // Clear session if prefix changed
    const previousPrefix = cache.get(`${prefixCacheKey}.${service}`);
    if (previousPrefix !== undefined && previousPrefix !== detectedPrefix) {
      logger.debug(`Prefix changed for '${service}' from '${previousPrefix}' to '${detectedPrefix}'`);
      clearSessionForService(service);
    }

    // Cache the new prefix with 5-minute TTL
    prefix = detectedPrefix;
    cache.put(`${prefixCacheKey}.${service}`, prefix, 1000 * 60 * 5);
  }

  widget.prefix = prefix;

  const url = new URL(formatApiCall(api, { endpoint, ...widget }));
  const params = { method: "GET", headers };
  setCookieHeader(url, params);

  // Retry logic for handling 401/404
  let retryCount = 0;
  const maxRetries = 2;

  while (retryCount <= maxRetries) {
    [status, contentType, data, responseHeaders] = await httpProxy(url, params);

    if ((status === 401 || status === 404) && !widget.key) {
      retryCount++;

      if (retryCount === 1) {
        logger.debug("Unifi rejected request, attempting login.");
        if (responseHeaders?.["x-csrf-token"]) {
          csrfToken = responseHeaders["x-csrf-token"];
        }

        [status, contentType, data, responseHeaders] = await login(widget, csrfToken);

        if (status !== 200) {
          logger.error("HTTP %d logging in to Unifi. Data: %s", status, data);
          return res.status(status).json({ error: { message: `HTTP Error ${status}`, url, data } });
        }

        const json = JSON.parse(data.toString());
        if (!(json?.meta?.rc === "ok" || json?.login_time || json?.update_time)) {
          logger.error("Error logging in to Unifi: Data: %s", data);
          return res.status(401).end(data);
        }

        addCookieToJar(url, responseHeaders);
        setCookieHeader(url, params);
        logger.debug("Retrying Unifi request after login.");
        continue;
      } else {
        logger.warn(`Too many ${status} responses for '${service}'. Clearing session.`);
        clearSessionForService(service);
        return res.status(status).json({
          error: { message: `Repeated HTTP ${status}. Session reset.`, url, data },
        });
      }
    }

    break; // Success or unhandled status
  }

  if (status !== 200) {
    logger.error("HTTP %d getting data from Unifi endpoint %s. Data: %s", status, url.href, data);
    return res.status(status).json({
      error: { message: `HTTP Error ${status}`, url, data },
    });
  }

  if (contentType) res.setHeader("Content-Type", contentType);
  return res.status(status).send(data);
}
