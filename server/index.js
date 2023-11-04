import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors'
import dotenv from 'dotenv'
import User from './modules/User.js';
import bcrypt from 'bcrypt';

dotenv.config();

const app=express();
app.use(express.json());

app.use(cors());
const connect=async()=>{
    try{
    await  mongoose.connect(process.env.MONGO_URL);
    console.log('Connected');
    }
    catch(error)
    {
        const {status,message}=error;
        console.log(status,message);

    }
}

app.post('/api/post',async(req,res)=>{
    const {name,email,password}=req.body;
    const user=new User({name,email,password})
   try{

   const savedUser=await user.save();
   res.json(savedUser)
   
}
catch(error){
    console.log(error.message);
}
});


app.get('/api/get/:id',async(req,res)=>{
    const {id} = req.params;
    try{
        const getId =await User.findById(id);
        res.json(getId);

    }catch(error){
        console.log(error.message);
    }
})

app.get('/api/get',async(req,res)=>{
    
    try{
        const getId =await User.find();
        res.json(getId);

    }catch(error){
        console.log(error.message);
    }
})

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
  
      if (!user) {
        console.log(`User with email ${email} not found`);
        return res.status(404).json({ error: 'User not found' });
      }
  
      const isPasswordValid = await user.comparePassword(password);
  
      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid password' });
      }
  
      res.json({ success: true, message: 'Login successful' });
  
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Server error' });
    }
  });



app.put('/api/update/:id', async (req, res) => {
    const id = req.params.id; 
    const updatedUser = req.body;
  
    try {
      const user = await User.findByIdAndUpdate(id, updatedUser, { new: true });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      return res.json({ message: 'User updated successfully', data: user });
    } catch (error) {
      console.error('Error updating user:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  });
  app.delete('/api/delete/:id',async(req,res)=>{
    const {id}= req.params;
    const{name,email,password}=req.body;
    console.log('ID from URL:', id);
    try {
       const result= await User.findByIdAndDelete(id);
       if (result) {
        res.json('User deleted successfully');
    } else {
        res.status(404).json('User not found');
    }
    } catch (error) {
        console.log(error.message)
        
    }
  })
  
  
   
  
  
  
  
  




app.listen(process.env.PORT,()=>{
    connect();
    console.log(`server is running on ${process.env.PORT}`)
})
