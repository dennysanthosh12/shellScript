FROM rhel:9.0
RUN groupadd -r mqbrkrs
RUN useradd -r -g mqbrkrs -m -d /home/eisuser -s /bin/bash eisuser
RUN mkdir -p /var/mqsi \
    && mkdir -p /var/mqsi/common/errors \
    && mkdir -p /var/mqsi/common/log \
    && mkdir -p /opt/IBM \
        && mkdir -p /opt/IBM/EndPoint_Public \
        && mkdir -p /opt/IBM/Keystore \
        && mkdir -p /opt/IBM/RSAKeystore 

ADD ./ace.tar.gz /opt/IBM/
COPY ./entrypoint.sh /opt/IBM/entrypoint.sh

RUN chmod +x /opt/IBM/entrypoint.sh
ENV ODBCSYSINI /opt/IBM/ace/server/ODBC/unixodbc
ENV ODBCINI /opt/IBM/ace/server/ODBC/unixodbc/odbc.ini

RUN cd /opt/IBM/ace && \
    .ace make registry global accept license silently

RUN echo 'source /opt/IBM/ace/server/bin/mqsiprofile' >> /etc/bashrc && \
    echo 'source /opt/IBM/ace/server/bin/mqsiprofile' > /etc/profile.d/ace.sh && \
    chmod +x /etc/profile.d/ace.sh

RUN chown -R eisuser:mqbrkrs /var/mqsi && \
    chmod -R 775 /var/mqsi && \
    chown -R eisuser:mqbrkrs /opt/IBM && \
    chmod -R 775 /opt/IBM

USER eisuser

ENTRYPOINT ["/opt/IBM/entrypoint.sh"]
