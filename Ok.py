from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(force=True)
    items = data.get("items", [])

    if isinstance(items, list) and len(items) == len(set(items)):
        return jsonify({"status": "Ok"})
    else:
        return jsonify({"status": "Error", "message": "Duplicates or bad data"}), 400

if __name__ == "__main__":
    app.run(port=5000, debug=True)
