# lambdas/process_document/Dockerfile
FROM public.ecr.aws/lambda/python:3.11

# Copy requirements and install them
COPY requirements.txt ${LAMBDA_TASK_ROOT}
RUN pip install --no-cache-dir -r requirements.txt

# Copy the actual code
COPY app.py ${LAMBDA_TASK_ROOT}

# Set the handler
CMD ["app.lambda_handler"]