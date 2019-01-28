import Vue from 'vue';
import App from './App.vue';
import store from './store';

Vue.config.productionTip = false;

import GoogleSigninButton from '@/components/GoogleSigninButton';
Vue.component('g-signin-button', GoogleSigninButton);

import BootstrapVue from 'bootstrap-vue';
import 'bootstrap/dist/css/bootstrap.css';
import 'bootstrap-vue/dist/bootstrap-vue.css';
Vue.use(BootstrapVue);

new Vue({
    render: h => h(App),
    store
}).$mount('#app');