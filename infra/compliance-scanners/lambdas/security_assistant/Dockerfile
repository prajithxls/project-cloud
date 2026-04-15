# Bump to Python 3.12 (Amazon Linux 2023) to support modern pre-compiled wheels
FROM public.ecr.aws/lambda/python:3.12

# Copy requirements first
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Install dependencies directly (no compilers needed!)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Lambda function code
COPY app.py ${LAMBDA_TASK_ROOT}

# Tell Lambda which function to run
CMD ["app.lambda_handler"]