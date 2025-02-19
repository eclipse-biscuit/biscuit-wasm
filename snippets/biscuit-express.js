export function middleware(options) {
  // assumes the token is in the `Authorization` header,
  // prefixed with `Bearer `
  const defaultExtractor = function (req) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new Error("Missing Authorization header");
    }
    if (!authHeader.startsWith("Bearer ")) {
      throw new Error("Authorization header does not carry a bearer token");
    }

    return authHeader.slice(7);
  };

  const defaultParser = function (data, publicKey) {
    return Biscuit.fromBase64(data, publicKey);
  };

  const defaultOnError = function (errorType, error, req, res, next) {
    if (error instanceof Error) {
      console.error(`Failed ${errorType}: ${error.toString()}`);
    } else {
      console.error(`Failed ${errorType}: ${JSON.stringify(error)}`);
    }

    switch (errorType) {
      case "extraction":
        res.status(401).send();
        return;
      case "verification":
        res.status(403).send();
        return;
      case "authorization":
        res.status(403).send();
        return;
      default:
        return;
    }
  };

  const applyAuthorizerBuilder = (authorizer, makeAuthorizer, req) => {
    if (typeof makeAuthorizer === "function") {
      authorizer.merge(makeAuthorizer(req));
    } else if (makeAuthorizer) {
      authorizer.merge(makeAuthorizer);
    }
  };

  const { publicKey, priorityAuthorizer, fallbackAuthorizer } = options;
  const tokenExtractor = options.tokenExtractor ?? defaultExtractor;
  const tokenParser = options.tokenParser ?? defaultParser;
  const onError = options.onError ?? defaultOnError;

  return function (makeAuthorizer) {
    return function (req, res, next) {
      try {
        const serializedToken = tokenExtractor(req);
        try {
          const token = tokenParser(serializedToken, publicKey);
          try {
            let authorizerBuilder = new Authorizer();
            applyAuthorizerBuilder(authorizerBuilder, priorityAuthorizer, req);
            applyAuthorizerBuilder(authorizerBuilder, makeAuthorizer, req);
            applyAuthorizerBuilder(authorizerBuilder, fallbackAuthorizer, req);

            let authorizer = authorizerBuilder.buildAuthenticated(token);
            const result = authorizer.authorize();
            req.biscuit = {
              token,
              authorizer,
              result,
            };
            next();
          } catch (e) {
            onError("authorization", e, req, res, next);
          }
        } catch (e) {
          onError("verification", e, req, res, next);
        }
      } catch (e) {
        onError("extraction", e, req, res, next);
      }
    };
  };
}
