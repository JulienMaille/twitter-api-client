class TwitterResponseError(Exception):
    def __init__(self, code, message="", data=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def __str__(self):
        return f"TwitterResponseError: {self.code} {self.message} {self.data}"

    def __repr__(self):
        return f"<TwitterResponseError [{self.code} {self.message} {self.data}]>"


TwitterResponseErrorCodeUnauthorized = 401
TwitterResponseErrorCodeRateLimit = 429
TwitterResponseErrorCodeAccountLocked = 326
TwitterResponseErrorCodeUnknown = 999
