FROM public.ecr.aws/lambda/python:3.12-x86_64
RUN pip install --upgrade pip
COPY requirements.txt  .
RUN  pip3 install -U -r requirements.txt --target "${LAMBDA_TASK_ROOT}"
COPY app.py ${LAMBDA_TASK_ROOT}/
COPY alignment.txt ${LAMBDA_TASK_ROOT}/
CMD [ "app.lambda_handler" ]