# Use Python 3.12 (latest supported by AWS Lambda)
FROM public.ecr.aws/lambda/python:3.12

# Set working directory
WORKDIR ${LAMBDA_TASK_ROOT}

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --default-timeout=1000 --no-cache-dir -r requirements.txt --upgrade

# Copy application code
COPY app.py .

# Set the handler
CMD ["app.lambda_handler"]