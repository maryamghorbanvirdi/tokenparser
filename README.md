This is a small helper library to extract attribute from token

To deploy to local maven repository please run this command:

mvn clean install

mvn install:install-file -Dfile=target/token-parser-1.0.0.jar -DgroupId=token-parser -DartifactId=token-parser -Dversion=1.0.0 -Dpackaging=jar

How to use it in your project: Just include this dependency in your pom.xml

 <dependency>
            <groupId>token-parser</groupId>
            <artifactId>token-parser</artifactId>
            <version>1.0.0</version>
 </dependency>
