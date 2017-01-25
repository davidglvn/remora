FROM python:2-onbuild
MAINTAINER David Golovan <https://github.com/davidglvn>

EXPOSE 7070

CMD [ "python", "./main.py" ]
