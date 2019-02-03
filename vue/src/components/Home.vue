<template>
    <div>
        <Nav/>
        <h1>authenticated server communication status: {{ healthCheck }}</h1>
    </div>
</template>

<script>
import Nav from '@/components/Nav';
import {mapGetters, mapActions} from 'vuex';

export default {
    name: 'Home',
    components: {
        Nav
    },
    computed: {
        ...mapGetters('auth',[
            'healthCheck'
        ])
    },
    async mounted() {
        this.fetchHealthCheck();
    },
    methods: {
        ...mapActions('auth',[
            'fetchHealthCheck'
        ])
    },
};
</script>
