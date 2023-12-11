FROM southamerica-east1-docker.pkg.dev/oystr-presto-test/docker-default/oystr-base-java:v2.0.0

ADD lib  /opt/morbid/service/lib
ADD bin  /opt/morbid/service/bin

RUN mkdir -p /etc/service/morbid-service
ADD run      /etc/service/morbid-service/run

