FROM eclipse-temurin:17-jre-alpine

EXPOSE 8081

COPY target/user-service-0.0.1-SNAPSHOT.jar app.jar

ENTRYPOINT ["java","-jar","/app.jar"]