FROM openjdk:17
WORKDIR /app
COPY . .

RUN ./mvnw clean package

ENTRYPOINT ["java", "-jar", "target/signapp-1.0.jar"]
