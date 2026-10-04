# Use a slim Python image for a smaller final image size
FROM ghcr.io/astral-sh/uv:python3.14-bookworm

# Set the working directory in the container
WORKDIR /app

# Copy the rest of the application code
COPY . .

# Install dependencies using uv
RUN uv sync

# Command to run the application
CMD ["uv", "run", "main.py"]