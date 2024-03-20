FROM nginx:1.21.3-alpine

# Configure NGINX
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf

# Copy static files
COPY --from=build-stage /app/config/staticfiles /var/www/html/static
RUN chown -R nginx:nginx /var/www/html
