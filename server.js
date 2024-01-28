import express from "express";
import mongoose from "mongoose";
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from 'firebase-admin';
import serviceAccount from './mern-blog-app-151f6-firebase-adminsdk-3sbml-0e963d2d6f.json' assert { type: "json" }
import { getAuth } from 'firebase-admin/auth';
import aws from 'aws-sdk';

// schema imports
import User from './Schema/User.js'
import Blog from './Schema/Blog.js'

// This code snippet sets up a server using Express and connects it to a MongoDB database using Mongoose. 
// It also includes various routes for user authentication, blog creation, and fetching blog data. 
// It uses various libraries like bcrypt for password hashing, jwt for token


const server = express(); // initializer for my express server
let PORT = 3000;

// firebase admin
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});


// regex expression patterns
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password


 // this will allow our server to accept data from any port, not just port 3000
//  setting up cross-origin response server for server communitcation
server.use(cors());
server.use(express.json())

// connect to the db via mongoose
mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
})

// setting the s3 bucket
const s3 = new aws.S3({
    region: 'eu-north-1',
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
})

//  generate the upload url
const generateUploadUrl = async () => {

    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`

    return await s3.getSignedUrlPromise('putObject', {
        Bucket: 'medium-clone-mern',
        Key: imageName,
        Expires: 1000,
        ContentType: 'image/jpeg',
    })
}

// creating a dynamic username.
// in the case where the domain is different, but the username already exists, 
// I want to be able to create a random string and add it to the end of that username to make it unique.
const generateUsername = async (email) => {
    let username = email.split("@")[0];

    let usernameExists = await User.exists({ "personal_info.username": username}).then((result) => result) // returns a bolean if the objects exists in the db

    usernameExists ? username += nanoid().substring(0, 5) : "";  // using nanoid to generate random extra strings
    return username;
}

// create a format to send the data
let formatedDataSend = (user) => {
    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY) // access token string
    return ({
        access_token,
        "fullname": user.personal_info.fullname,
        "username": user.personal_info.username,
        "profile_img":user.personal_info.profile_img
    })
}

// verifies the jwt(json web token)
const verifyJWT = (req, res, next) => {
    const authHeader = req.header('authorization');
    const token = authHeader && authHeader.split(" ")[1]; // get item from the first args whicj is the access token

    if(token == null){
        return res.status(403).json({ "error": "Access token is required" })
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if(err){
            return res.status(403).json({ "error": "Access token is required" })
        }

        req.user = user.id;
        next()
    })

}

// upload image url route
server.get('/get-upload-url', (req, res) => {
    generateUploadUrl()
    .then(url => res.status(200).json({ uploadUrl: url }))
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ "error": err.message })
    })
})

// posting the data from the signup form to mongodb
server.post('/signup', (req, res) => {
    let { fullname, email, password } = req.body; // the data from the req page

    if(fullname.length < 3) {
        return res.status(403).json({"error" : "fullname must be at least 3 characters long"})
    }

    if(!email.length) {  // the same as if(email.length == 0)
        return res.status(403).json({"error": "Enter your email"})
    }

    if(!emailRegex.test(email)) {  // verifying the email regex
        return res.status(403).json({ "error": "email is invalid"})
    }

    if(!passwordRegex.test(password)) { //verifying the pwd regex
        return res.status(403).json({ "error": "Password should be 6 t0 20 characters long with a numeric, 1 lowercase and 1 uppercase letter!"})
    }

    // hashing the password and salting it 10 times for more security
    bcrypt.hash(password, 10, async (err, hashed_pwd) => {
        let username = await generateUsername(email)
        // creating new user
        let user = new User({
            personal_info: {
                fullname,    
                email,
                username,
                password: hashed_pwd
            }
        })

        // saving the data to mongodb
        user.save()
        .then((u) => {
            return res.status(200).json(formatedDataSend(u))
        
        })
        // error handling
        .catch(err => {
            if(err.code == 11000) {
                return res.status(500).json({ 'error': 'email already exists'})
            }
            return res.status(500).json({'error': err.message })
        })

        
    })

})

// login route
server.post('/signin', (req, res) => {
    let { email, password } = req.body;

    // searching through the db to find out if user already exists
    User.findOne({ "personal_info.email": email })
    .then((user) => {
        if(!user) {
            return res.status(403).json({ "error": "email not found"})
        }
        

        // comparing the password with the hashed password in the db
        bcrypt.compare( password, user.personal_info.password, (err, result) => {
            if(err) {
                return res.status(500).json({ "error": "Error occured during login. Please try again."})
            }
            if(!result) {
                return res.status(403).json({ "error": "Password is incorrect"})
            } else {
                return res.status(200).json(formatedDataSend(user))
            }
        })

    }).catch(err => {
        console.log(err.message);
        return res.status(500).json({ "error": err.message})
    
    })
})

// get user data during google authentication
server.post("/google-auth", async (req, res) => {

    let { access_token } = req.body;

    getAuth().verifyIdToken(access_token)
    .then(async (decodedUser) => {
        // decoded data of the user
        let { email, picture, name } = decodedUser; // destructuring just the data we need

        picture = picture.replace('s96-c', 's384-c'); // to get the highest resolution of the profile image

        let user = await User.findOne({"personal_info.email": email}).select("personlan_info.username personal_info.fullname personal_info.profile_img google_auth")
        .then((u) => {
            return u || null;
        })
        .catch((err) => {
            console(err.message)
            return res.status(500).json({"error": err.message});
        })

        // if user exists, and did not create an account with google, but it trying to login with google, inform the user and ask him/her to sign in with email.
        if(user) { //login
            if(!user.google_auth) { // google auth is part of our user schema that returns a bolean
                return res.status(403).json({"error": "This account was created without google provider. Please login with email to access this account!"});
            }
        }
        // for first time users, we are going to create a new user in our database
        else { // signup
            let username = generateUsername(email);
            
            // creating new user
            user = new User({
                personal_info: {
                    fullname: name,
                    username,
                    email,
                    profile_img: picture
                },
                google_auth: true
            })

            // saving the data to mongodb
            await user.save().then((u) => {
                user = u;
            })
            .catch((err) => {
                return res.status(500).json({"error": err.message})
            })
        }

        return res.status(200).json(formatedDataSend(user))

    })
    // error handling for the google authentication
    .catch((err) => {
        res.status(500).json({"error": "Failed to authenticate with google. Try with another account or provider!"})
    })
})

// get the latest blogs
server.post('/latest-blogs', (req, res) => {
    let maxLimit = 5;
    let { page } = req.body;

    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })

})

// get the blog latest blog count
server.get("/count-latest-blogs", (req, res) => {
    Blog.countDocuments({ draft: false })
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err.message)
        return res.status(500).json({ error: err.message })
    })
})


// trending blogs
server.get('/trending-blogs', (req, res) => {
    let maxLimit = 5;

    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 })
    .select("blog_id title publishedAt -_id")
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

// get blog by categories
server.post('/search-blogs', (req, res) => {
    let { tag, page, query, author, limit, eliminate_curr_blog } = req.body;

    let findQuery;
    if(tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_curr_blog } };
    } else if(query){
        findQuery = { title: new RegExp(query, 'i'), draft: false }
    } else if(author){
        findQuery = { draft: false, author: author }
    }

    let maxLimit = limit ? limit : 5;

    Blog.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_reads": -1 })
    .select("blog_id title publishedAt banner activity tags -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})

// get the search blogs count
server.get('/count-search-blogs', (req, res) => {
    let { tag, query, author } = req.body;

    let findQuery;
    if(tag) {
        findQuery = { tags: tag, draft: false };
    } else if(query){
        findQuery = { title: new RegExp(query, 'i'), draft: false }
    } else if(author){
        findQuery = { draft: false, author: author }
    }

    Blog.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err.message)
        return res.status(500).json({ error: err.message })
    })
})

// get users by search term
server.post('/search-users', (req, res) => {
    let { query } = req.body;

    if (!query) {
        return res.status(400).json({ error: 'Search term is required' });
    }

    User.find({ "personal_info.username": new RegExp(query, 'i') })
    .select("personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .limit(50)
    .then(users => {
        return res.status(200).json({ users })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})

// get the user profile using the url parameters
server.get('/user-profile/:username', (req, res) => {

    let { username } = req.params;

    User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -blogs -updatedAt _id")
    .then(user => {
        if(!user) {
            return res.status(404).json({ error: "User not found" })
        }

        return res.status(200).json({ user })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})

// posting blog data to the db
server.post('/create-blog', verifyJWT, async (req, res) => {

    let authorId = req.user;

    // destructure the data from the blog
    let { title, des, content, tags, banner, draft } = req.body;

    if(!title.length) {
        return res.status(403).json({ error: "You need to provide a title!" })
    }
    
    if(!draft){
        // error handling and data vallidation
    
        if(!des.length || des.length > 200) {
            return res.status(403).json({ error: "You must provide a description under 200 characters to publish the blog" })
        }
    
        if(!banner.length) {
            return res.status(403).json({ error: "You must provide a blog banner to publish the blog" })
        }
    
        if(!content.blocks.length) {
            return res.status(403).json({ error: "You must provide some content to for publishing" })
        }
    
        if(!tags.length || tags.length > 10) {
            return res.status(403).json({ error: "You must provide a tag to publish the blog." })
        }

    }


    // storing the data to my db
    tags = tags.map(tag => tag.toLowerCase())  //  converting all tags to lowercase which will help during sorting

    let blog_id = title.replace(/[^a-zA-Z0-9]/g, '').replace(/\s+/g, "-").trim() + nanoid();  // dynamic route replacement string with regex and nanoid

    let blog = new Blog({ 
        title,
        des,
        content,
        tags,
        banner,
        draft,
        author: authorId,
        blog_id,
        draft: Boolean(draft)   // converting draft to a boolean instead of undefined
    })

    // saving the data to mongodb
    blog.save().then((blog) => {
        
        // increment the total blog post value
        let incrementVal = draft ? 0 : 1;

        User.findOneAndUpdate({ _id: authorId }, { $inc: { "account_info.total_posts" : incrementVal }, $push: { "blogs": blog._id } })
        .then(user => {
            return res.status(200).json({ id: blog.blog_id })
        })
        .catch(err => {
            return res.status(500).json({ error: "Failed to update total posts number"})
        })

    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

// get the blog base on it's id
server.get('/get_blog/:blog_id', (req, res) => {
    let { blog_id } = req.params;
    let incrementalVal = 1;

    // find and update the blog read count
    Blog.findOneAndUpdate({ blog_id }, { $inc : { "activity.total_reads": incrementalVal }})
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname presonal_info.profile_img -_id")
    .select("blog_id title tags des activity banner content publishedAt -_id")
    .then(blog => {

        // // update total read count for that user
        User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, { $inc: { "account_info.total_reads": incrementalVal }})
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

        // return from initial findOneAndUpdate
        return res.status(200).json({ blog })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})
// assign server to listening port
server.listen(PORT, () => {
    console.log(`listening to port -> ${PORT}`);
})
