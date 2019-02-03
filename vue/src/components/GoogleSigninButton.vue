<template>
    <b-button
        ref="signinBtn"
        :variant="`success`"
        class="btn-sign-in"
    >
        Sign In
    </b-button>
</template>

<script>
export default {
    name: 'GSigninButton',
    mounted () {
        setTimeout(() => {
            if(!window.gapi){
                // eslint-disable-next-line
                console.warn('error loading gapi??')
            }

            window.gapi.load('auth2', () => {
                const auth2 = window.gapi.auth2.init({
                    client_id: '817620866614-3j683eppkju965sjmamg6qf49rgtmmpq.apps.googleusercontent.com',
                    cookiepolicy: 'single_host_origin'
                });
                auth2.attachClickHandler(this.$refs.signinBtn, {}, googleUser => {
                    this.$emit('google-auth-done', googleUser);
                    // eslint-disable-next-line
                }, error => console.log(error))
            });

        },500); // TODO : need to make this more robust
    }
};
</script>

  