<template>
    <div>
        <Nav/>
        <h1>server communication status: {{ healthStatus }}</h1>
    </div>
</template>

<script>

import axios from 'axios';
import Nav from '@/components/Nav';

export default {
    name: 'Home',
    components: {
        Nav
    },
    data() {
        return {
            healthStatus: 'totally borken'
        };
    },
    async mounted() {

        try{ 
            const healthResponse = await axios.get('http://localhost:4001/health-check');
            this.healthStatus = healthResponse.data.message;
        }catch(error){
            // eslint-disable-next-line
      console.warn('error getting server health check',{error})
        }
    }
};
</script>
