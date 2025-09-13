# GRCAgent

This repository hosts a secure chat application built on top of a local Large Language Model (LLM). The service is implemented with FastAPI and incorporates several OWASP-recommended security practices.

## Features
- Local LLM loaded via [`llama-cpp-python`](https://github.com/abetlen/llama-cpp-python)
- API key authentication through the `X-API-Key` header
- Strict CORS configuration and input validation
- Rate limiting (5 requests per minute per IP) using `slowapi`
- Logs avoid storing raw user messages by hashing inputs
- Simple `/health` endpoint for monitoring

## Running
1. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
2. Set environment variables or create a `.env` file
   ```bash
   export LLM_MODEL_PATH=/path/to/model.bin
   export API_KEY=replace-with-secure-key
   export ALLOWED_ORIGINS=http://localhost:3000  # optional
   ```
3. Start the server
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000
   ```

For production deployments, run behind HTTPS and load secrets from a `.env` file or a dedicated secret manager.

