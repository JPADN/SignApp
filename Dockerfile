FROM openjdk:17
COPY out/artifacts/signapp_jar/signapp.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
