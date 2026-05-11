FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for tkinter and cryptography
RUN apt-get update && apt-get install -y \
    python3-tk \
    libtk8.6 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements if any, but since no requirements.txt, install directly
RUN pip install requests cryptography

COPY . .

CMD ["python", "client_gui.py"]