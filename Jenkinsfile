pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './mvnw clean package'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: '**/target/sonatype-plugin**.jar')
        archiveArtifacts(onlyIfSuccessful: true, artifacts: '**/target/sonatype-fortify-integration/**.jar')
      }
    }
  }
}
