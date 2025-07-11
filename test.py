from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/test', methods=['POST'])
def test():
    data = request.get_json()
    print("Received data:", data)
    return jsonify(data)

@app.route('/test', methods=['GET'])
def test_get():
    return "Hello! This is a GET response from /test."

if __name__ == '__main__':
    app.run(debug=True)