FROM nginx:1.27-alpine

RUN apk add --no-cache openssh \
    && echo "root:laboratorio" | chpasswd \
    && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && mkdir -p /var/run/sshd

COPY nginx.conf /etc/nginx/nginx.conf

# genera las claves del host en cada arranque (garantizado) y lanza ambos servicios
CMD ["/bin/sh", "-c", "ssh-keygen -A && /usr/sbin/sshd && nginx -g 'daemon off;'"]
