# Use the official AWS Lambda Python 3.11 base image
FROM public.ecr.aws/lambda/python:3.11

# Copy requirements first (Docker layer caching — only reinstalls if requirements change)
COPY requirements.txt .

# Install all dependencies into the Lambda task root
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Lambda function code
COPY app.py .

# Tell Lambda which function to run
CMD ["app.lambda_handler"]
