import Vue from 'vue'
import Router from 'vue-router'
import HelloWorld from '../components/onepage/HelloWorld.vue'

Vue.use(Router)

export default new Router({
  routes: [
    {
      path: '/',
      name: 'Hello',
      component: HelloWorld
    }
  ]
})
