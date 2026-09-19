FROM ubuntu:latest

RUN apt update \
    && apt install -y \
        gcc-arm-linux-gnueabi \
        less \
        make

CMD ["/bin/bash"]
