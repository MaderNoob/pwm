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
    pub fn rest(&self)->&[u8]{
        &self.vector[self.pos..]
    }
    pub fn rest_mut(&mut self)->&mut [u8]{
        &mut self.vector[self.pos..]
    }
    pub fn buffer(&self)->&[u8]{
        &self.vector
    }
}
