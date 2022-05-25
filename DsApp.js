const express = require("express");

const app = express()

app.use(express.json())

app.post('api/getsecurityobject', async (req, res) => {
    try {
        if(!req.body) res.send("Please pass required body")

        let responseDTO = req.body;
        let getAppConObj = await accountController.getSecurityObject(responseDTO);
        res.send(getAppConObj)
    } catch (error) {
        res.send(error)
    }
})