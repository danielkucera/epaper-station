FROM python:3-alpine

WORKDIR /station

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./station.py" ]
