FROM nginx:1.25.4-alpine

RUN rm -f /etc/nginx/conf.d/*

# Configure NGINX
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf

RUN chown -R nginx:nginx /var/cache/nginx && \
    chmod -R g+w /var/cache/nginx
RUN touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]