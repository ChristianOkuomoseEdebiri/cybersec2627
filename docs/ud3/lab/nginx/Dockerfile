FROM nginx:1.27-alpine
RUN apk add --no-cache openssh \
    && ssh-keygen -A \
    && echo "root:laboratorio" | chpasswd \
    && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY nginx.conf /etc/nginx/nginx.conf
CMD ["/bin/sh", "-c", "/usr/sbin/sshd && nginx -g 'daemon off;'"]
