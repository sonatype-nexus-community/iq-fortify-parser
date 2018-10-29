pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh './gradlew clean assemble'
      }
    }
    stage('Archive JAR') {
      steps {
        archiveArtifacts(onlyIfSuccessful: true, artifacts: 'target/Sonatype**.jar')
      }
    }
  }
}