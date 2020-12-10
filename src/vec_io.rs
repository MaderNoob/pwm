pub struct VecReader{
    vector:Vec<u8>,
    pos:usize,
}
impl VecReader{
    pub fn new(vec:Vec<u8>)->VecReader{
        VecReader{
            vector:vec,
            pos:0,
        }
    }
    pub fn read_exact(&mut self,buf:&mut [u8])->Result<(),()>{
        if self.pos+buf.len()<=self.vector.len(){
            buf.copy_from_slice(&self.vector[self.pos..self.pos+buf.len()]);
            self.pos+=buf.len();
            Ok(())
        }else{
            Err(())
        }
    }
    pub fn consume(&mut self,amount:usize){
        self.pos+=amount
    }
    pub fn seek_back(&mut self,amount:usize){
        if amount>self.pos{
            self.pos=0;
        }else{
            self.pos-=amount;
        }
    }
    pub fn rest(&self)->&[u8]{
        &self.vector[self.pos..]
    }
    pub fn rest_mut(&mut self)->&mut [u8]{
        &mut self.vector[self.pos..]
    }
    pub fn buffer(&self)->&[u8]{
        &self.vector
    }
    pub fn inner_vec(self)->Vec<u8>{
        self.vector
    }
    pub fn inner_vec_ref(&self)->&Vec<u8>{
        &self.vector
    }
    pub fn inner_vec_mut(&mut self)->&mut Vec<u8>{
        &mut self.vector
    }
    pub fn eof(&self)->bool{
        self.pos>=self.vector.len()
    }
}
