<template>
  <div>
    <h1>server communication status: {{ healthStatus }}</h1>
    <g-signin-button @google-auth-done="onSignIn"/>
  </div>
</template>

<script>

import axios from 'axios'

export default {
  name: 'HelloWorld',
  data() {
    return {
      healthStatus: 'totally borken'
    }
  },
  async mounted() {

    try{ 
      const healthResponse = await axios.get('http://localhost:4001/health-check');
      this.healthStatus = healthResponse.data.message
    }catch(error){

      // eslint-disable-next-line
      console.warn('error getting server health check',{error})
    }
  },
  methods: {
    onSignIn(dat){
      // eslint-disable-next-line
      console.log({dat})
    }
  }
}
</script>
