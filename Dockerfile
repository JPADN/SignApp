FROM openjdk:17
WORKDIR /
# COPY out/artifacts/signapp_jar/signapp.jar app.jar
COPY target/signapp-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
