with open("backend/llm/reasoner.py", "r") as f:
    text = f.read()
text = text.replace('"format": "json",', '"format": schema,')
with open("backend/llm/reasoner.py", "w") as f:
    f.write(text)
