<template>
    <div>
        <Nav/>
        <b-button
            :variant="`primary`"
            class="btn-sign-in"
            @click="fetchHealthCheck"
        >
            fetchHealthCheck
        </b-button>
        <h4>authenticated server communication status: </h4>
        <pre>{{ healthCheck }}</pre>
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
    methods: {
        ...mapActions('auth',[
            'fetchHealthCheck'
        ])
    },
};
</script>
