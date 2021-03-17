import express from 'express'
import bodyParser from 'body-parser'
import mongoose from 'mongoose'
import cors from 'cors'
import dotenv from 'dotenv'

import postRoutes from './routes/posts.js'

const app = express()
dotenv.config()

app.use(bodyParser.json({ limit: '15mb', extended: true }))
app.use(bodyParser.urlencoded({ limit: '15mb', extended: true }))
app.use(cors())

app.use('/posts', postRoutes)

app.get('/', (req, res) => {
    res.send("Hello to memories api.")
})

//Connect to DB
const CONNECTION_URL = process.env.CONNECTION_URL

const PORT = process.env.PORT || 5000

mongoose.connect(CONNECTION_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`)
        })
    })
    .catch((err) => {
        console.log(err);
    })

mongoose.set('useFindAndModify', false)