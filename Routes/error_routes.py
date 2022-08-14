from flask import jsonify
from Routes import Routes

@Routes.errorhandler(404)
def route_not_found(e):
    return jsonify({"error": True, "message": "The requested url was not found!", "code": "NOT_FOUND"}), 404


@Routes.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": True, "message": "Too many requests. Please try again later.", "code": "TOO_MANY_REQUESTS"}), 429


@Routes.errorhandler(500)
def server_error_handler(e):
    return jsonify({"error": True, "message": "Internal server error!", "code": "SERVER_ERROR"}), 500


@Routes.errorhandler(405)
def method_not_allowed_handler(e):
    return jsonify({"error": True, "message": "Method rejected by server!", "code": "REJECTED"}), 405