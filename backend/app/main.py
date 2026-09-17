from fastapi import FastAPI
app = FastAPI()

@app.post("/internal/scan")
def scan():
    return {"verdict": "forward", "mode": "sanitize", "sanitized_messages": []}

@app.post("/internal/verify")
def verify():
    return {"verdict": "forward", "mode": "sanitize"}
