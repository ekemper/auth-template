<template>
    <div>
        <b-navbar
            toggleable="md"
            type="dark"
            variant="info">

            <b-navbar-toggle target="nav_collapse"/>

            <b-navbar-brand href="#">NavBar</b-navbar-brand>

            <b-collapse
                id="nav_collapse"
                is-nav>

                <b-navbar-nav>
                    <b-nav-item href="#">Link</b-nav-item>
                </b-navbar-nav>

                <!-- Right aligned nav items -->
                <b-navbar-nav class="ml-auto">
                   

                    <b-img
                        v-show="hasImage"
                        rounded="circle"
                        width="60"
                        height="60"
                        alt="img"
                        class="m-1" />

                    <b-nav-item-dropdown
                        v-if="googleUser"
                        right
                    >
                        <!-- Using button-content slot -->
                        <template slot="button-content">
                            <em>{{ googleUser.fullName }}</em>
                        </template>
                        <b-dropdown-item href="#">Profile</b-dropdown-item>
                        <b-dropdown-item
                            href="#"
                            @click="logout">Signout</b-dropdown-item>
                    </b-nav-item-dropdown>
                    

                    <g-signin-button
                        v-show="!googleUser"
                        @google-auth-done="onSignIn"/>

                </b-navbar-nav>

            </b-collapse>
        </b-navbar>
    </div>
</template>

<script>
import {mapGetters, mapActions} from 'vuex';

export default {
    name: 'Nav',
    computed: {
        ...mapGetters('auth',[
            'googleUser',
        ]),
        hasImage() {
            return this.googleUser && this.googleUser.profileImage;
        }
    },
    beforeMount() {
        this.checkForLoggedInUser();
    },
    methods: {
        onSignIn(rawGoogleUser){
            this.parseGoogleUser({rawGoogleUser});
        },
        ...mapActions('auth',[
            'logout',
            'checkForLoggedInUser',
            'parseGoogleUser'
        ]),
    },
};
</script>

<style >
.b-navbar-nav {
    display: flex
}
</style>
